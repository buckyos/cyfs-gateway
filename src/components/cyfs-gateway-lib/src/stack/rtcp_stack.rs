pub struct RtcpStackInner {}

pub struct RtcpStack {}

impl RtcpStack {
    pub fn builder() -> RtcpStackBuilder {
        RtcpStackBuilder::new()
    }
}

pub struct RtcpStackBuilder {}

impl RtcpStackBuilder {
    fn new() -> Self {
        Self {}
    }
}
