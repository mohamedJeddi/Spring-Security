package com.example.secservice.sec;

public interface SecurityParams {

    public static final String JWT_HEADER_NAME = "Authorization";
    public static final String SECRET = "medjeddi@2019";
    public static final long EXPIRATION = 24*3600*1000;
    public static final String HEADER_PREFIX = "Bearer ";

}
