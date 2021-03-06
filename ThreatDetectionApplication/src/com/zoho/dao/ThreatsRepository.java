package com.zoho.dao;

public interface ThreatsRepository<K,V> {
	void save(K key, V value);
	V find(K key);
}
