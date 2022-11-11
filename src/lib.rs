#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
#![allow(clippy::all)]

//! Rust wrapper for the `aws-c-http` library. For testing purposes only.
//! For interacting with AWS services, use the `aws-sdk-rust` crate instead.

use {
    scratchstack_wrapper_aws_c_common::{
        aws_allocator, aws_array_list, aws_byte_buf, aws_byte_cursor, aws_crt_statistics_category_t, aws_hash_table,
        aws_ref_count, aws_string,
    },
    scratchstack_wrapper_aws_c_io::{
        aws_channel, aws_client_bootstrap, aws_event_loop, aws_input_stream, aws_server_bootstrap,
        aws_socket_channel_bootstrap_options, aws_socket_endpoint, aws_socket_options, aws_tls_connection_options,
    },
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests;