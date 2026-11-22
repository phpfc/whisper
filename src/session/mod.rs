/// Validation constants
pub const MAX_USERNAME_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 1000;

/// Validates a username (1-32 chars, alphanumeric + underscore)
pub fn validate_username(username: &str) -> Result<(), &'static str> {
    if username.is_empty() {
        return Err("Username cannot be empty");
    }
    if username.len() > MAX_USERNAME_LEN {
        return Err("Username too long (max 32 characters)");
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err("Username can only contain letters, numbers, and underscores");
    }
    Ok(())
}
