use crate::Error;

pub(crate) type TlsIncoming<TS> = futures::stream::BoxStream<'static, Result<TS, Error>>;
