#[cfg(debug_assertions)]
macro_rules! my_debug {
    ( $( $x:expr ),* ) => {
        $(
            dbg!($x);
        )*
    };
}

#[cfg(not(debug_assertions))]
macro_rules! my_debug {
    ($x:expr) => {
        std::convert::identity($x)
    };
    ($( $x:expr ),* ) => {
        ()
    };
}
