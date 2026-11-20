use std::{error::Error, net::Ipv6Addr, path::PathBuf, time::Duration};

use chrono::Utc;
use datum_connect_daemon::galactic_masque::{ConnectionDescriptor, ManagedSession, TransportPool};
use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    credential_urls: [String; 2],
    denied_credential_url: String,
    token_file: PathBuf,
    targets: [Ipv6Addr; 2],
    protocol: String,
}

async fn descriptor(
    http: &reqwest::Client,
    url: &str,
    token: &str,
) -> Result<ConnectionDescriptor> {
    let response = http.post(url).bearer_auth(token).send().await?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("credential API returned {}", response.status()).into());
    }
    if response
        .headers()
        .get("cache-control")
        .and_then(|value| value.to_str().ok())
        != Some("no-store")
    {
        return Err("credential API must return no-store".into());
    }
    let bytes = response.bytes().await?;
    if bytes.len() > 65536 {
        return Err("oversized descriptor".into());
    }
    Ok(ConnectionDescriptor::parse(&bytes, Utc::now())?)
}

async fn attach(
    pool: &TransportPool,
    descriptor: &ConnectionDescriptor,
    protocol: &str,
) -> Result<ManagedSession> {
    let cancel = CancellationToken::new();
    match protocol {
        "h3" => pool
            .connect_h3(descriptor, cancel)
            .await
            .map(ManagedSession::H3),
        "h2" => pool
            .connect_h2(descriptor, cancel)
            .await
            .map(ManagedSession::H2),
        _ => return Err("protocol must be h3 or h2".into()),
    }
    .map_err(|_| "CONNECT-IP attachment rejected".into())
}

fn identity(session: &ManagedSession) -> (usize, u64) {
    match session {
        ManagedSession::H3(value) => (value.connection_id(), value.stream_id()),
        ManagedSession::H2(value) => (value.connection_id(), u64::from(value.stream_id())),
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo(source: Ipv6Addr, target: Ipv6Addr, nonce: [u8; 16]) -> Vec<u8> {
    let mut packet = vec![0_u8; 64];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&24_u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&target.octets());
    packet[40] = 128;
    packet[44..48].copy_from_slice(&nonce[..4]);
    packet[48..64].copy_from_slice(&nonce);
    let mut pseudo = packet[8..40].to_vec();
    pseudo.extend_from_slice(&24_u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&packet[40..]);
    packet[42..44].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    packet
}

async fn ping(
    session: &ManagedSession,
    descriptor: &ConnectionDescriptor,
    target: Ipv6Addr,
) -> Result<()> {
    let observed = session.observed();
    let plan = descriptor.verify_provider_plan(observed.assigned, &observed.advertised)?;
    if !plan.routes.iter().any(|route| route.contains(&target)) {
        return Err("target outside authorized routes".into());
    }
    let nonce = rand::random::<[u8; 16]>();
    let request = echo(plan.host_address, target, nonce);
    session
        .send(request.clone())
        .await
        .map_err(|_| "packet send failed")?;
    tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(packet) = session.recv().await {
            if packet.len() != 64
                || packet[0] >> 4 != 6
                || packet[4..8] != [0, 24, 58, packet[7]]
                || packet[40..42] != [129, 0]
            {
                continue;
            }
            if packet[8..24] != target.octets()
                || packet[24..40] != plan.host_address.octets()
                || packet[44..64] != request[44..64]
            {
                continue;
            }
            let mut pseudo = packet[8..40].to_vec();
            pseudo.extend_from_slice(&24_u32.to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 58]);
            pseudo.extend_from_slice(&packet[40..]);
            if checksum(&pseudo) == 0 {
                return Ok(());
            }
        }
        Err::<(), Box<dyn Error>>("stream ended before echo reply".into())
    })
    .await
    .map_err(|_| "echo reply timeout")?
}

fn evidence(phase: &str, protocol: &str, sessions: &[ManagedSession; 2]) {
    let identities = sessions.iter().map(identity).collect::<Vec<_>>();
    println!(
        "{}",
        json!({"phase": phase, "protocol": protocol, "observedAt": Utc::now(), "sameConnection": identities[0].0 == identities[1].0, "streamIds": [identities[0].1, identities[1].1]})
    );
}

async fn confirm(
    lines: &mut tokio::io::Lines<BufReader<tokio::io::Stdin>>,
    expected: &str,
) -> Result<()> {
    eprintln!(
        "Operator: perform {expected}; type exactly {expected} after observed reconciliation."
    );
    if lines.next_line().await?.as_deref() != Some(expected) {
        return Err("operator phase not confirmed".into());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: managed-gateway-e2e CONFIG.json")?;
    let mut config: Config = serde_json::from_slice(&std::fs::read(&path)?)?;
    for url in config
        .credential_urls
        .iter()
        .chain(std::iter::once(&config.denied_credential_url))
    {
        let url = url::Url::parse(url)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("credential URL must be plain HTTPS without query/userinfo".into());
        }
    }
    let token = std::fs::read_to_string(config.token_file)?;
    let http = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()?;
    let mut descriptors = [
        descriptor(&http, &config.credential_urls[0], token.trim()).await?,
        descriptor(&http, &config.credential_urls[1], token.trim()).await?,
    ];
    if descriptors[0].binding == descriptors[1].binding
        || descriptors[0].transport.authority != descriptors[1].transport.authority
        || descriptors[0].transport.vpc_selector == descriptors[1].transport.vpc_selector
    {
        return Err("requires distinct bindings/VPCs on the same authority".into());
    }
    if descriptors[0]
        .network_plan
        .destination_prefixes
        .iter()
        .any(|first| {
            descriptors[1]
                .network_plan
                .destination_prefixes
                .iter()
                .any(|second| {
                    first.contains(&second.network()) || second.contains(&first.network())
                })
        })
    {
        return Err("overlapping local route contexts are not qualified".into());
    }
    let mut pool = TransportPool::default();
    let mut sessions = [
        attach(&pool, &descriptors[0], &config.protocol).await?,
        attach(&pool, &descriptors[1], &config.protocol).await?,
    ];
    if identity(&sessions[0]).0 != identity(&sessions[1]).0
        || identity(&sessions[0]).1 == identity(&sessions[1]).1
    {
        return Err("streams did not share exactly one transport".into());
    }
    for index in 0..2 {
        ping(&sessions[index], &descriptors[index], config.targets[index]).await?;
    }
    evidence("two-vpc-packets", &config.protocol, &sessions);
    let mut replay = descriptors[0].clone();
    replay.transport.vpc_selector = descriptors[1].transport.vpc_selector.clone();
    if attach(&pool, &replay, &config.protocol).await.is_ok() {
        return Err("cross-VPC credential replay accepted".into());
    }
    evidence("cross-vpc-replay-denied", &config.protocol, &sessions);
    let denied = http
        .post(&config.denied_credential_url)
        .bearer_auth(token.trim())
        .send()
        .await?;
    if denied.status() != reqwest::StatusCode::FORBIDDEN {
        return Err("out-of-policy third binding did not return Forbidden".into());
    }
    for index in 0..2 {
        ping(&sessions[index], &descriptors[index], config.targets[index]).await?;
    }
    evidence(
        "third-binding-denied-siblings-alive",
        &config.protocol,
        &sessions,
    );
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    confirm(&mut lines, "binding-a-revoked").await?;
    if ping(&sessions[0], &descriptors[0], config.targets[0])
        .await
        .is_ok()
        || attach(&pool, &descriptors[0], &config.protocol)
            .await
            .is_ok()
    {
        return Err("revoked binding still forwards or reconnects".into());
    }
    ping(&sessions[1], &descriptors[1], config.targets[1]).await?;
    evidence("binding-revoked-sibling-alive", &config.protocol, &sessions);
    confirm(&mut lines, "binding-a-restored").await?;
    sessions[0].cancel();
    descriptors[0] = descriptor(&http, &config.credential_urls[0], token.trim()).await?;
    sessions[0] = attach(&pool, &descriptors[0], &config.protocol).await?;
    if identity(&sessions[0]).0 != identity(&sessions[1]).0 {
        return Err("restored attachment did not reuse surviving transport".into());
    }
    for index in 0..2 {
        ping(&sessions[index], &descriptors[index], config.targets[index]).await?;
    }
    evidence("binding-restored", &config.protocol, &sessions);
    confirm(&mut lines, "network-a-recreated").await?;
    if ping(&sessions[0], &descriptors[0], config.targets[0])
        .await
        .is_ok()
        || attach(&pool, &descriptors[0], &config.protocol)
            .await
            .is_ok()
    {
        return Err("old network incarnation still authorizes".into());
    }
    let stale = http
        .post(&config.credential_urls[0])
        .bearer_auth(token.trim())
        .send()
        .await?;
    if stale.status() != reqwest::StatusCode::FORBIDDEN {
        return Err("old binding minted after network recreation".into());
    }
    ping(&sessions[1], &descriptors[1], config.targets[1]).await?;
    evidence(
        "network-recreated-old-binding-denied",
        &config.protocol,
        &sessions,
    );
    confirm(&mut lines, "binding-a-rebound").await?;
    config.targets = serde_json::from_slice::<Config>(&std::fs::read(&path)?)?.targets;
    sessions[0].cancel();
    descriptors[0] = descriptor(&http, &config.credential_urls[0], token.trim()).await?;
    sessions[0] = attach(&pool, &descriptors[0], &config.protocol).await?;
    for index in 0..2 {
        ping(&sessions[index], &descriptors[index], config.targets[index]).await?;
    }
    evidence("network-rebound", &config.protocol, &sessions);
    confirm(&mut lines, "certificate-rotated").await?;
    for session in &sessions {
        session.cancel();
    }
    pool = TransportPool::default();
    for index in 0..2 {
        descriptors[index] =
            descriptor(&http, &config.credential_urls[index], token.trim()).await?;
        sessions[index] = attach(&pool, &descriptors[index], &config.protocol).await?;
        ping(&sessions[index], &descriptors[index], config.targets[index]).await?;
    }
    if identity(&sessions[0]).0 != identity(&sessions[1]).0 {
        return Err("rotated streams did not share fresh transport".into());
    }
    evidence("fresh-tls-after-rotation", &config.protocol, &sessions);
    confirm(&mut lines, "endpoint-disabled").await?;
    if ping(&sessions[1], &descriptors[1], config.targets[1])
        .await
        .is_ok()
        || attach(&pool, &descriptors[1], &config.protocol)
            .await
            .is_ok()
    {
        return Err("disabled endpoint still forwards or reconnects".into());
    }
    evidence("endpoint-disabled", &config.protocol, &sessions);
    for session in &sessions {
        session.cancel();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmpv6_echo_has_valid_pseudoheader_checksum() {
        let packet = echo(
            "fd00::1".parse().unwrap(),
            "fd00::2".parse().unwrap(),
            [42; 16],
        );
        let mut pseudo = packet[8..40].to_vec();
        pseudo.extend_from_slice(&24_u32.to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]);
        pseudo.extend_from_slice(&packet[40..]);
        assert_eq!(checksum(&pseudo), 0);
    }
}
