use {
    bindgen::builder,
    std::{
        env::var,
        fs::{copy, create_dir_all, read_dir},
        path::{Path, PathBuf},
    },
};

const LINK_LIBS: &str = r#"
aws-c-http
aws-c-compression
aws-c-io
aws-c-common
aws-c-cal
s2n
crypto
ssl
"#;
const INCLUDE_PATH: &str = "aws/http";
const DEP_LIBRARIES: &str = r#"aws-c-common
aws-c-io"#;
const FUNCTIONS: &str = r#"
aws_http_library_init
aws_http_library_clean_up
aws_http_status_text
aws_http_connection_manager_acquire
aws_http_connection_manager_release
aws_http_connection_manager_new
aws_http_connection_manager_acquire_connection
aws_http_connection_manager_release_connection
aws_http_connection_manager_fetch_metrics
aws_http_client_connect
aws_http_connection_release
aws_http_connection_close
aws_http_connection_stop_new_requests
aws_http_connection_is_open
aws_http_connection_new_requests_allowed
aws_http_connection_is_client
aws_http_connection_get_version
aws_http_connection_get_channel
aws_http_alpn_map_init_copy
aws_http_alpn_map_init
aws_http_options_validate_proxy_configuration
aws_http2_connection_change_settings
aws_http2_connection_ping
aws_http2_connection_get_local_settings
aws_http2_connection_get_remote_settings
aws_http2_connection_send_goaway
aws_http2_connection_get_sent_goaway
aws_http2_connection_get_received_goaway
aws_http2_connection_update_window
aws_http2_stream_manager_acquire
aws_http2_stream_manager_release
aws_http2_stream_manager_new
aws_http2_stream_manager_acquire_stream
aws_http2_stream_manager_fetch_metrics
aws_http_proxy_negotiator_acquire
aws_http_proxy_negotiator_release
aws_http_proxy_strategy_create_negotiator
aws_http_proxy_strategy_acquire
aws_http_proxy_strategy_release
aws_http_proxy_strategy_new_basic_auth
aws_http_proxy_strategy_new_tunneling_adaptive
aws_http_proxy_config_new_from_connection_options
aws_http_proxy_config_new_from_manager_options
aws_http_proxy_config_new_tunneling_from_proxy_options
aws_http_proxy_config_new_from_proxy_options
aws_http_proxy_config_new_clone
aws_http_proxy_config_destroy
aws_http_proxy_options_init_from_config
aws_http_proxy_new_socket_channel
aws_http_header_name_eq
aws_http_headers_new
aws_http_headers_acquire
aws_http_headers_release
aws_http_headers_add_header
aws_http_headers_add
aws_http_headers_add_array
aws_http_headers_set
aws_http_headers_count
aws_http_headers_get_index
aws_http_headers_get
aws_http_headers_has
aws_http_headers_erase
aws_http_headers_erase_value
aws_http_headers_erase_index
aws_http_headers_clear
aws_http2_headers_get_request_method
aws_http2_headers_set_request_method
aws_http2_headers_get_request_scheme
aws_http2_headers_set_request_scheme
aws_http2_headers_get_request_authority
aws_http2_headers_set_request_authority
aws_http2_headers_set_request_authority
aws_http2_headers_set_request_path
aws_http2_headers_get_response_status
aws_http2_headers_set_response_status
aws_http_message_new_request
aws_http_message_new_request_with_headers
aws_http_message_new_response
aws_http2_message_new_request
aws_http2_message_new_response
aws_http2_message_new_from_http1
aws_http_message_acquire
aws_http_message_release
aws_http_message_destroy
aws_http_message_is_request
aws_http_message_is_response
aws_http_message_get_protocol_version
aws_http_message_get_request_method
aws_http_message_set_request_method
aws_http_message_get_request_path
aws_http_message_set_request_path
aws_http_message_get_response_status
aws_http_message_set_response_status
aws_http_message_get_body_stream
aws_http_message_set_body_stream
aws_http1_stream_write_chunk
aws_http2_stream_write_data
aws_http1_stream_add_chunked_trailer
aws_http_message_get_headers
aws_http_message_get_const_headers
aws_http_message_get_header_count
aws_http_message_get_header
aws_http_message_add_header
aws_http_message_add_header_array
aws_http_message_erase_header
aws_http_connection_make_request
aws_http_stream_new_server_request_handler
aws_http_stream_release
aws_http_stream_activate
aws_http_stream_get_connection
aws_http_stream_get_incoming_response_status
aws_http_stream_get_incoming_request_method
aws_http_stream_get_incoming_request_uri
aws_http_stream_send_response
aws_http_stream_update_window
aws_http_stream_get_id
aws_http2_stream_reset
aws_http2_stream_get_received_reset_error_code
aws_http2_stream_get_sent_reset_error_code
aws_http_server_new
aws_http_server_release
aws_http_connection_configure_server
aws_http_connection_is_server
aws_crt_statistics_http1_channel_init
aws_crt_statistics_http1_channel_cleanup
aws_crt_statistics_http1_channel_reset
aws_crt_statistics_http2_channel_init
aws_crt_statistics_http2_channel_reset
aws_websocket_is_data_frame
aws_websocket_client_connect
aws_websocket_release
aws_websocket_close
aws_websocket_send_frame
aws_websocket_increment_read_window
aws_websocket_convert_to_midchannel_handler
aws_websocket_get_channel
aws_websocket_random_handshake_key
aws_http_message_new_websocket_handshake_request
"#;
const TYPES: &str = r#"
aws_http_errors
aws_http2_error_code
aws_http_log_subject
aws_http_version
aws_http_method_connect
aws_http_method_options
aws_http_header_method
aws_http_header_scheme
aws_http_header_authority
aws_http_header_path
aws_http_header_status
aws_http_scheme_http
aws_http_scheme_https
aws_http_connection_manager
aws_http_connection_manager_on_connection_setup_fn
aws_http_connection_manager_shutdown_complete_fn
aws_http_manager_metrics
aws_http_connection_manager_options
aws_http_connection
aws_http_on_client_connection_setup_fn
aws_http_on_client_connection_shutdown_fn
aws_http2_on_change_settings_complete_fn
aws_http2_on_ping_complete_fn
aws_http2_on_goaway_received_fn
aws_http2_on_remote_settings_change_fn
aws_http_statistics_observer_fn
aws_http_connection_monitoring_options
aws_http1_connection_options
aws_http2_connection_options
aws_http_client_connection_options
aws_http2_settings_id
aws_http2_setting
aws_http2_stream_manager
aws_http2_setting
aws_http_make_request_options
aws_http2_stream_manager_on_stream_acquired_fn
aws_http2_stream_manager_shutdown_complete_fn
aws_http2_stream_manager_options
aws_http2_stream_manager_acquire_stream_options
aws_http_proxy_config
aws_http_proxy_authentication_type
aws_http_proxy_env_var_type
aws_http_proxy_connection_type
proxy_env_var_settings
aws_http_proxy_options
aws_http_proxy_negotiation_get_token_sync_fn
aws_http_proxy_negotiation_get_challenge_token_sync_fn
aws_http_proxy_negotiation_terminate_fn
aws_http_proxy_negotiation_http_request_forward_fn
aws_http_proxy_negotiation_http_request_transform_async_fn
aws_http_proxy_negotiation_http_request_transform_fn
aws_http_proxy_negotiation_connect_on_incoming_headers_fn
aws_http_proxy_negotiator_connect_status_fn
aws_http_proxy_negotiator_connect_on_incoming_body_fn
aws_http_proxy_negotiation_retry_directive
aws_http_proxy_negotiator_get_retry_directive_fn
aws_http_proxy_negotiator_forwarding_vtable
aws_http_proxy_negotiator_tunnelling_vtable
aws_http_proxy_negotiator
aws_http_proxy_strategy_create_negotiator_fn
aws_http_proxy_strategy_vtable
aws_http_proxy_strategy
aws_http_proxy_strategy_basic_auth_options
aws_http_proxy_strategy_tunneling_kerberos_options
aws_http_proxy_strategy_tunneling_ntlm_options
aws_http_proxy_strategy_tunneling_adaptive_options
aws_http_proxy_strategy_tunneling_sequence_options
aws_http_stream
aws_http_header_compression
aws_http_header
aws_http_headers
aws_http_header_block
aws_http_message
aws_http_message_transform_complete_fn
aws_http_message_transform_fn
aws_http_on_incoming_headers_fn
aws_http_on_incoming_header_block_done_fn
aws_http_on_incoming_body_fn
aws_http_on_incoming_request_done_fn
aws_http_on_stream_complete_fn
aws_http_on_stream_destroy_fn
aws_http_make_request_options
aws_http_request_handler_options
aws_http_stream_write_complete_fn
aws_http1_stream_write_chunk_complete_fn
aws_http1_chunk_extension
aws_http1_chunk_options
aws_http2_stream_write_data_complete_fn
aws_http2_stream_write_data_options
aws_http_server
aws_http_server_on_incoming_connection_fn
aws_http_server_on_destroy_fn
aws_http_server_options
aws_http_on_incoming_request_fn
aws_http_on_server_connection_shutdown_fn
aws_http_server_connection_options
aws_crt_http_statistics_category
aws_crt_statistics_http1_channel
aws_crt_statistics_http2_channel
aws_http_status_code
aws_websocket
aws_websocket_opcode
aws_websocket_on_connection_setup_fn
aws_websocket_on_connection_shutdown_fn
aws_websocket_incoming_frame
aws_websocket_on_incoming_frame_begin_fn
aws_websocket_on_incoming_frame_payload_fn
aws_websocket_on_incoming_frame_complete_fn
aws_websocket_client_connection_options
aws_websocket_stream_outgoing_payload_fn
aws_websocket_outgoing_frame_complete_fn
aws_websocket_send_frame_options
"#;

const VARS: &str = "
aws_http_method_get
aws_http_method_head
aws_http_method_post
aws_http_method_put
aws_http_method_delete
";

fn get_include_dir<P: AsRef<Path>>(dir: P) -> PathBuf {
    let mut result = PathBuf::from(dir.as_ref());

    for folder in INCLUDE_PATH.split('/') {
        result.push(folder);
    }

    result
}

fn main() {
    let root = PathBuf::from(var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let out_dir = PathBuf::from(var("OUT_DIR").expect("OUT_DIR not set"));

    let src_include_dir = root.join("include");
    let dst_include_dir = out_dir.join("include");
    let src_lib_include_dir = get_include_dir(&src_include_dir);
    let dst_lib_include_dir = get_include_dir(&dst_include_dir);
    let src_include_dir_str = src_include_dir.to_string_lossy();
    let dst_include_dir_str = dst_include_dir.to_string_lossy();
    let src_lib_include_dir_str = src_lib_include_dir.to_string_lossy();
    let dst_lib_include_dir_str = dst_lib_include_dir.to_string_lossy();

    println!("cargo:include={dst_include_dir_str}");
    println!("cargo:rerun-if-changed=include");
    println!("cargo:rerun-if-env-changed=AWS_CRT_PREFIX");

    if let Ok(aws_crt_prefix) = var("AWS_CRT_PREFIX") {
        println!("cargo:rustc-link-search={aws_crt_prefix}/lib");
    }

    for library_name in LINK_LIBS.split('\n') {
        let library_name = library_name.trim();
        if !library_name.is_empty() {
            println!("cargo:rustc-link-lib={library_name}");
        }
    }

    // Copy include files over
    create_dir_all(&dst_lib_include_dir)
        .unwrap_or_else(|e| panic!("Unable to create directory {dst_lib_include_dir_str}: {e}"));

    let mut builder = builder()
        .clang_arg(format!("-I{src_include_dir_str}"))
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .derive_eq(true)
        .allowlist_recursively(false); // Don't dive into dependent libraries.
    
    for dep in DEP_LIBRARIES.split('\n') {
        let dep = dep.trim();
        if dep.is_empty() {
            continue;
        }

        let dep = String::from(dep).replace('-', "_").to_uppercase();
        let dep_include_dir = PathBuf::from(var(format!("DEP_{dep}_INCLUDE")).unwrap_or_else(|_| panic!("DEP_{dep}_INCLUDE not set")));
        let dep_include_dir_str = dep_include_dir.to_string_lossy();
        builder = builder.clang_arg(format!("-I{dep_include_dir_str}"));
    }

    let mut n_includes = 0;

    for entry in read_dir(&src_lib_include_dir)
        .unwrap_or_else(|e| panic!("Unable to list header files in {src_lib_include_dir_str}: {e}"))
    {
        let entry =
            entry.unwrap_or_else(|e| panic!("Unable to read directory entry in {src_lib_include_dir_str}: {e}"));
        let file_name_string = entry.file_name();
        let src_path = src_lib_include_dir.join(&file_name_string);
        let src_path_str = src_path.to_string_lossy();
        let dst_path = dst_lib_include_dir.join(&file_name_string);

        if entry.file_type().unwrap_or_else(|e| panic!("Unable to read file type of {src_path_str}: {e}")).is_file() {
            // Only include header files ending with .h; ignore .inl.
            let file_name_utf8 = file_name_string.to_str().expect("Unable to convert file name to UTF-8");
            if file_name_utf8.ends_with(".h") {
                builder = builder.header(src_path_str.to_string());
                n_includes += 1;
            }

            // Copy all files to the output directory.
            copy(&src_path, &dst_path).unwrap_or_else(|e| {
                panic!(
                    "Failed to copy from {src_path_str} to {dst_path_str}: {e}",
                    dst_path_str = dst_path.to_string_lossy()
                )
            });
        }
    }

    if n_includes == 0 {
        panic!("No header files found in {src_lib_include_dir_str}");
    }

    for function_pattern in FUNCTIONS.split('\n') {
        let function_pattern = function_pattern.trim();
        if !function_pattern.is_empty() {
            builder = builder.allowlist_function(function_pattern);
        }
    }

    for type_pattern in TYPES.split('\n') {
        let type_pattern = type_pattern.trim();
        if !type_pattern.is_empty() {
            builder = builder.allowlist_type(type_pattern);
        }
    }

    for var_pattern in VARS.split('\n') {
        let var_pattern = var_pattern.trim();
        if !var_pattern.is_empty() {
            builder = builder.allowlist_var(var_pattern);
        }
    }

    let bindings_filename = out_dir.join("bindings.rs");
    let bindings = builder.generate().expect("Unable to generate bindings");
    bindings.write_to_file(&bindings_filename).unwrap_or_else(|e| {
        panic!(
            "Failed to write bindings to {bindings_filename_str}: {e}",
            bindings_filename_str = bindings_filename.to_string_lossy()
        )
    });

    if cfg!(any(target_os = "ios", target_os = "macos")) {
        println!("cargo:rustc-link-arg=-framework");
        println!("cargo:rustc-link-arg=CoreFoundation");
    }
}
