pub mod s2n_tls_intercept;
pub mod transcript;

// basic test -> 1 message, 1 record,
// harder test -> 2 messages, 1 record,
// hardest test -> 1 message, 2 records,

// how funky can the message framing get?
// would this be allowed? I certainly hope not.
// but it seems like a simple thing that would make maintainers lives easier, so
// it probably is allowed
// |         record          |        record     |
// |  message   |    message        |  message   |
