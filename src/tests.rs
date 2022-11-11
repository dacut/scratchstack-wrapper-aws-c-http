#[test]
fn test_init_uninit() {
    use {
        crate::{aws_http_library_clean_up, aws_http_library_init},
        scratchstack_wrapper_aws_c_common::aws_default_allocator,
    };

    unsafe {
        aws_http_library_init(aws_default_allocator());
        aws_http_library_clean_up();
    }
}
