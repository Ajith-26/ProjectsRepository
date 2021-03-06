package com.zoho.dao;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.rocksdb.Options;
import org.rocksdb.RocksDB;
import org.rocksdb.RocksDBException;

public class ThreatsRepositoryImplementation implements ThreatsRepository<String,String>{

	private final static String NAME = "threats-db";
	private File dbDir;
	private RocksDB db;
	
	public ThreatsRepositoryImplementation() {
		RocksDB.loadLibrary();
	    final Options options = new Options();
	    options.setCreateIfMissing(true);
	    dbDir = new File("/rocks-db", NAME);
	    try {
	      Files.createDirectories(dbDir.getParentFile().toPath());
	      Files.createDirectories(dbDir.getAbsoluteFile().toPath());
	      db = RocksDB.open(options, dbDir.getAbsolutePath());
	    } catch(IOException | RocksDBException ex) {
	      System.err.println("Error initializng RocksDB,exception: "+ex.getCause()+" message: "+ex.getMessage()+" stackTrace: "+ex.getStackTrace());
	    }
	}
	@Override
	public void save(String key, String value) {
		try {
		      db.put(key.getBytes(), value.getBytes());
		} catch (RocksDBException e) {
		      System.err.println("Error saving entry in RocksDB, cause: "+ e.getCause()+" message: "+ e.getMessage());
		}
		
	}
	@Override
	public String find(String key) {
	    String result = null;
	    try {
	      byte[] bytes = db.get(key.getBytes());
	      if(bytes != null) 
	    	  result = new String(bytes);
	    } catch (RocksDBException e) {
	            System.err.println("Error retrieving the entry in RocksDB from key: "+key+"cause: "+e.getCause()+"message: "+ e.getMessage());
	    }
	    return result;
	}

}
