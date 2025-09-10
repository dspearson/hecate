use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Duration, Utc};
use sqlx::{sqlite::SqlitePool, FromRow, Row};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct ApiToken {
    pub id: i64,
    pub user_id: i64,
    pub token_hash: String,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Clone, FromRow)]
pub struct UploadSession {
    pub id: String,
    pub user_id: i64,
    pub filename: String,
    pub total_size: i64,
    pub bytes_received: i64,
    pub chunks_received: String, // JSON array
    pub temp_path: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed: bool,
}

pub struct UserManager {
    pool: Arc<SqlitePool>,
    argon2: Argon2<'static>,
}

impl UserManager {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePool::connect(database_url)
            .await
            .context("Failed to connect to database")?;

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("Failed to run migrations")?;

        Ok(Self {
            pool: Arc::new(pool),
            argon2: Argon2::default(),
        })
    }

    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        quota_bytes: Option<i64>,
    ) -> Result<User> {
        // Hash password
        let salt = SaltString::generate(&mut rand::thread_rng());
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?
            .to_string();

        let quota = quota_bytes.unwrap_or(10 * 1024 * 1024 * 1024); // 10GB default

        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (username, email, password_hash, quota_bytes)
            VALUES (?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind(quota)
        .fetch_one(self.pool.as_ref())
        .await
        .context("Failed to create user")?;

        Ok(user)
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        let user =
            sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ? AND is_active = 1")
                .bind(username)
                .fetch_optional(self.pool.as_ref())
                .await
                .context("Failed to query user")?;

        match user {
            Some(u) => {
                let parsed_hash = PasswordHash::new(&u.password_hash)
                    .map_err(|e| anyhow::anyhow!("Invalid password hash in database: {}", e))?;

                if self
                    .argon2
                    .verify_password(password.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    Ok(Some(u))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub async fn get_user_by_id(&self, user_id: i64) -> Result<Option<User>> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(self.pool.as_ref())
            .await
            .context("Failed to query user")?;

        Ok(user)
    }

    pub async fn update_used_bytes(&self, user_id: i64, delta: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE users 
            SET used_bytes = used_bytes + ?, 
                updated_at = CURRENT_TIMESTAMP 
            WHERE id = ?
            "#,
        )
        .bind(delta)
        .bind(user_id)
        .execute(self.pool.as_ref())
        .await
        .context("Failed to update used bytes")?;

        Ok(())
    }

    pub async fn check_quota(&self, user_id: i64, required_bytes: i64) -> Result<bool> {
        let row =
            sqlx::query("SELECT quota_bytes - used_bytes as available FROM users WHERE id = ?")
                .bind(user_id)
                .fetch_one(self.pool.as_ref())
                .await
                .context("Failed to check quota")?;

        let available: i64 = row.get("available");
        Ok(available >= required_bytes)
    }

    pub async fn create_api_token(
        &self,
        user_id: i64,
        name: Option<String>,
        expires_in: Option<Duration>,
    ) -> Result<String> {
        let token = Uuid::new_v4().to_string();
        let token_hash = sha256::digest(&token);

        let expires_at = expires_in.map(|d| Utc::now() + d);

        sqlx::query(
            r#"
            INSERT INTO api_tokens (user_id, token_hash, name, expires_at)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(user_id)
        .bind(&token_hash)
        .bind(name)
        .bind(expires_at)
        .execute(self.pool.as_ref())
        .await
        .context("Failed to create API token")?;

        Ok(token)
    }

    pub async fn authenticate_token(&self, token: &str) -> Result<Option<User>> {
        let token_hash = sha256::digest(token);

        let user_id = sqlx::query(
            r#"
            SELECT user_id FROM api_tokens 
            WHERE token_hash = ? 
                AND is_active = 1 
                AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(self.pool.as_ref())
        .await
        .context("Failed to query token")?
        .map(|row| row.get::<i64, _>("user_id"));

        match user_id {
            Some(id) => {
                // Update last_used_at
                sqlx::query(
                    "UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = ?",
                )
                .bind(&token_hash)
                .execute(self.pool.as_ref())
                .await?;

                self.get_user_by_id(id).await
            }
            None => Ok(None),
        }
    }

    pub async fn create_upload_session(
        &self,
        user_id: i64,
        filename: &str,
        total_size: i64,
        temp_path: &str,
    ) -> Result<String> {
        let session_id = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::hours(24);

        sqlx::query(
            r#"
            INSERT INTO upload_sessions (id, user_id, filename, total_size, temp_path, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&session_id)
        .bind(user_id)
        .bind(filename)
        .bind(total_size)
        .bind(temp_path)
        .bind(expires_at)
        .execute(self.pool.as_ref())
        .await
        .context("Failed to create upload session")?;

        Ok(session_id)
    }

    pub async fn get_upload_session(&self, session_id: &str) -> Result<Option<UploadSession>> {
        let session = sqlx::query_as::<_, UploadSession>(
            r#"
            SELECT * FROM upload_sessions 
            WHERE id = ? 
                AND completed = 0 
                AND expires_at > CURRENT_TIMESTAMP
            "#,
        )
        .bind(session_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .context("Failed to query upload session")?;

        Ok(session)
    }

    pub async fn update_upload_progress(
        &self,
        session_id: &str,
        bytes_received: i64,
        chunk_indices: &[u32],
    ) -> Result<()> {
        let chunks_json = serde_json::to_string(chunk_indices)?;

        sqlx::query(
            r#"
            UPDATE upload_sessions 
            SET bytes_received = ?, chunks_received = ?
            WHERE id = ?
            "#,
        )
        .bind(bytes_received)
        .bind(chunks_json)
        .bind(session_id)
        .execute(self.pool.as_ref())
        .await
        .context("Failed to update upload progress")?;

        Ok(())
    }

    pub async fn complete_upload_session(&self, session_id: &str) -> Result<()> {
        sqlx::query("UPDATE upload_sessions SET completed = 1 WHERE id = ?")
            .bind(session_id)
            .execute(self.pool.as_ref())
            .await
            .context("Failed to complete upload session")?;

        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) -> Result<usize> {
        let result = sqlx::query(
            r#"
            DELETE FROM upload_sessions 
            WHERE expires_at < CURRENT_TIMESTAMP 
                OR (completed = 1 AND created_at < datetime('now', '-1 day'))
            "#,
        )
        .execute(self.pool.as_ref())
        .await
        .context("Failed to cleanup expired sessions")?;

        Ok(result.rows_affected() as usize)
    }

    pub async fn log_audit(
        &self,
        user_id: Option<i64>,
        action: &str,
        details: Option<serde_json::Value>,
        ip_address: Option<&str>,
    ) -> Result<()> {
        let details_str = details.map(|d| d.to_string());

        sqlx::query(
            r#"
            INSERT INTO audit_log (user_id, action, details, ip_address)
            VALUES (?, ?, ?, ?)
            "#,
        )
        .bind(user_id)
        .bind(action)
        .bind(details_str)
        .bind(ip_address)
        .execute(self.pool.as_ref())
        .await
        .context("Failed to log audit")?;

        Ok(())
    }
}

mod sha256 {
    use sha2::{Digest, Sha256};

    pub fn digest(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}
