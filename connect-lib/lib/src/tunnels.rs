// Stub — full implementation in Wave 2
// TunnelService for tunnel CRUD operations

#[derive(Debug, Clone)]
pub struct TunnelService;

#[derive(Debug, Clone)]
pub struct TunnelSummary;

#[derive(Debug, Clone)]
pub enum TunnelDeleteOutcome {
    Deleted,
    NotFound,
    Error(String),
}
