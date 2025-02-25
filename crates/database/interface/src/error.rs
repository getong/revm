use core::convert::Infallible;

/// Database error marker is needed to implement From conversion for Error type.
pub trait DBErrorMarker {}

/// Implement marker for `()`.
impl DBErrorMarker for () {}
impl DBErrorMarker for Infallible {}
impl DBErrorMarker for String {}
