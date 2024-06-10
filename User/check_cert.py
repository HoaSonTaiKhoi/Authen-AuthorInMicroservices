# from OpenSSL import crypto

# def check_certificate(crt_file_path):
#     with open(crt_file_path, 'rb') as crt_file:
#         crt_data = crt_file.read()

#     # Giải mã và phân tích chứng chỉ
#     cert = crypto.load_certificate(crypto.FILETYPE_PEM, crt_data)
    
#     # Lấy thông tin chứng chỉ
#     subject = cert.get_subject()
#     issuer = cert.get_issuer()
#     common_name = subject.CN
#     issued_by = issuer.CN
#     expiration_date = cert.get_notAfter()

#     # In ra thông tin chứng chỉ
#     print("Thông tin chứng chỉ:")
#     print("Tên chung của chứng chỉ:", common_name)
#     print("Được phát bởi:", issued_by)
#     print("Ngày hết hạn:", expiration_date.decode('utf-8'))

# # Sử dụng hàm kiểm tra chứng chỉ
# check_certificate('./certificate.crt')

from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime

def check_cert(cert_file):
    # Đọc tệp chứng chỉ
    with open(cert_file, 'rb') as file:
        cert_data = file.read()

    # Phân tích cú pháp chứng chỉ
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    # Kiểm tra xem chứng chỉ đã hết hạn hay chưa
    is_valid = cert.not_valid_after > datetime.datetime.now()

    # In thông tin chứng chỉ
    print(cert)
    print(f"Valid: {is_valid}")

    return is_valid