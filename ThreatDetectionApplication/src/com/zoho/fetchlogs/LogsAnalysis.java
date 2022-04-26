package com.zoho.fetchlogs;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Scanner;
import org.json.JSONObject;
import com.zoho.dao.ThreatsRepository;
import com.zoho.dao.ThreatsRepositoryImplementation;

public class LogsAnalysis {
	
	private final String exact_file_path = "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log";
	private final String sample_file_path = "I:\\sample_files\\SampleLogFile.txt";
	private HttpClient client;
	private HttpRequest request;
	private HttpResponse<String> response;
	private ThreatsRepository<String,String> threatsDB = new ThreatsRepositoryImplementation();
	public void analyseLogs() {
		try {
			File logFile = new File(sample_file_path);
			Scanner logFileReader = new Scanner(logFile);
			//ignoring first 5 lines of description
			for(int i=0;i<5;i++)
				logFileReader.nextLine();  
			while (logFileReader.hasNextLine()) {
				 // process each line
				 String data = logFileReader.nextLine();
				 //split the fields
				 String[] parts = data.split(" ");
				 //ip address field which our system access
				 String ipAddr = parts[5];
				 String threatAlreadyPresent = threatsDB.find(ipAddr);
				 // if ipAddress is not present in DB
				 if(threatAlreadyPresent == null) {
					 JSONObject threatFound = threatPresent(ipAddr); 
					 if(threatFound!=null) {
						 //print the threat
						 System.out.println("\nThreat is found for ip address: "+ipAddr);
						 System.out.println("Timestamp: "+parts[0]+" "+parts[1]);
						 System.out.println(threatFound.toString(4));
						 //	add in db with key as ip address
						 threatsDB.save(ipAddr,threatFound.toString());	
					 }
				 }
				// if ipAddress is already present in DB, then it's a threat so just print info
				 else {
					 System.out.println("\nThreat is found for ip address: "+ipAddr);
					 System.out.println("Timestamp: "+parts[0]+" "+parts[1]);
					 System.out.println(new JSONObject(threatAlreadyPresent).toString(4));
				 }
			}
			logFileReader.close();
		} 
		catch (FileNotFoundException e) {
			   System.out.println("Error:"+e.getMessage());
			   e.printStackTrace();
		}
	}
	private JSONObject threatPresent(String ipAddr) {
		client = HttpClient.newHttpClient();
        request = HttpRequest.newBuilder()
                .uri(URI.create("https://api.ipregistry.co/"+ipAddr+"?key=9mv56mm2dpln5e18&fields=security,ip,connection,company"))
                .build();
		try {
			response = client.send(request,HttpResponse.BodyHandlers.ofString());
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
        JSONObject jsonObj = new JSONObject(response.body());
        if(jsonObj.has("security")) {
        	JSONObject siteInfo = new JSONObject(jsonObj.get("security").toString());
        	if(siteInfo.getBoolean("is_abuser") || siteInfo.getBoolean("is_attacker") || siteInfo.getBoolean("is_threat")) 
        		return jsonObj;
        }
        return null;
	}
}
