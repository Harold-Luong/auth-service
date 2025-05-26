package com.ecommerce.auth.entity;

public enum Role {
    USER,           // Người dùng chung (đang dùng để test)
    GUEST,          // Khách vãng lai
    CUSTOMER,       // Người mua
    SELLER,         // Người bán
    ADMIN,          // Quản trị toàn quyền
    MODERATOR,      // Kiểm duyệt viên
    WAREHOUSE_STAFF,// Nhân viên kho
    SHIPPER         // Đối tác vận chuyển
}