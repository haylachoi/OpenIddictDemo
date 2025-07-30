Device flow
##### Test với Aspire dashboard
- Xem log của device để lấy link xác nhận.
- Sau khi xác nhận xong thì device sẽ tự polling để lấy token.

##### Test với file .http
- Đầu tiên là gọi `/connect/device` để lấy `device_code`.
- Vào link được trả về từ `/connect/device` để xác nhận.
- Sau đó là gọi `/connect/token` với `device_code` để lấy token.