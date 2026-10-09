CREATE DATABASE IF NOT EXISTS divine_hope_shop CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE divine_hope_shop;

CREATE TABLE IF NOT EXISTS admins (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS products (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(180) NOT NULL,
  slug VARCHAR(200) NOT NULL UNIQUE,
  category VARCHAR(80) NOT NULL,
  description TEXT NOT NULL,
  image_url VARCHAR(1000) NULL,
  price_pesewas INT UNSIGNED NOT NULL,
  stock_quantity INT UNSIGNED NOT NULL DEFAULT 0,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_products_active_category (active, category)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS orders (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  public_reference CHAR(36) NOT NULL UNIQUE,
  customer_name VARCHAR(160) NOT NULL,
  customer_email VARCHAR(254) NOT NULL,
  customer_phone VARCHAR(40) NOT NULL,
  shipping_address TEXT NOT NULL,
  notes TEXT NULL,
  currency CHAR(3) NOT NULL DEFAULT 'GHS',
  total_pesewas INT UNSIGNED NOT NULL,
  status ENUM('pending_payment','paid','processing','shipped','completed','cancelled','payment_failed') NOT NULL DEFAULT 'pending_payment',
  payment_provider VARCHAR(30) NOT NULL DEFAULT 'paystack',
  payment_reference VARCHAR(120) NULL UNIQUE,
  paid_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_orders_status_created (status, created_at),
  INDEX idx_orders_customer_email (customer_email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS order_items (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  order_id BIGINT UNSIGNED NOT NULL,
  product_id BIGINT UNSIGNED NULL,
  product_name VARCHAR(180) NOT NULL,
  unit_price_pesewas INT UNSIGNED NOT NULL,
  quantity SMALLINT UNSIGNED NOT NULL,
  line_total_pesewas INT UNSIGNED NOT NULL,
  CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
  CONSTRAINT fk_order_items_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS payment_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  provider_event_id VARCHAR(160) NULL UNIQUE,
  event_type VARCHAR(100) NOT NULL,
  order_reference CHAR(36) NULL,
  payload JSON NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_payment_events_order (order_reference)
) ENGINE=InnoDB;

-- Add initial products through the admin dashboard after setting up the admin account.
