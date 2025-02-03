//! [`ToSql`] and [`FromSql`] implementation for [`Ulid`].
use crate::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use crate::Result;
use ulid::Ulid;

/// Serialize `Ulid` to text.
impl ToSql for Ulid {
    #[inline]
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.to_string()))
    }
}

/// Deserialize text to `Url`.
impl FromSql for Ulid {
    #[inline]
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Text(s) => {
                let s = std::str::from_utf8(s).map_err(|e| FromSqlError::Other(Box::new(e)))?;
                s.parse().map_err(|e| FromSqlError::Other(Box::new(e)))
            }
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{params, Connection, Error, Result};
    use ulid::{DecodeError, Ulid};

    fn checked_memory_handle() -> Result<Connection> {
        let db = Connection::open_in_memory()?;
        db.execute_batch("CREATE TABLE ulids (i INTEGER, v TEXT)")?;
        Ok(db)
    }

    fn get_url(db: &Connection, id: i64) -> Result<Ulid> {
        db.query_row("SELECT v FROM ulids WHERE i = ?", [id], |r| r.get(0))
    }

    #[test]
    fn test_sql_ulid() -> Result<()> {
        let db = &checked_memory_handle()?;

        let url0 = Ulid::new();

        db.execute(
            "INSERT INTO ulids (i, v) VALUES (0, ?1), (1, ?2)",
            // also insert a non-hex encoded url (which might be present if it was
            // inserted separately)
            params![url0, "illegal"],
        )?;

        assert_eq!(get_url(db, 0)?, url0);

        // Make sure the conversion error comes through correctly.
        let err = get_url(db, 1).unwrap_err();
        match err {
            Error::FromSqlConversionFailure(_, _, e) => {
                assert_eq!(
                    *e.downcast::<DecodeError>().unwrap(),
                    DecodeError::InvalidLength
                );
            }
            e => {
                panic!("Expected conversion failure, got {e}");
            }
        }
        Ok(())
    }
}
