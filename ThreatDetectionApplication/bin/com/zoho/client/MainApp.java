package com.zoho.client;
import com.zoho.fetchlogs.LogsAnalysis;

public class MainApp {
	public static void main(String[] args) throws Exception{
		LogsAnalysis  service = new LogsAnalysis();
		service.analyseLogs();
	}
}
