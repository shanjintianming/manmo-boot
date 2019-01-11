package com.cloud;

import javax.sql.DataSource;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import com.alibaba.druid.pool.DruidDataSource;

@SpringBootApplication
@ServletComponentScan//这行是为了避免扫描不到Druid的Servle
@EnableTransactionManagement
@MapperScan("com.interview.*.dao")
@EnableCaching
public class ServerBootApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServerBootApplication.class, args);
	}
	
	@Bean(name = "duridDatasource")
    @ConfigurationProperties(prefix="spring.datasource")
    public DataSource druidDataSource() { 
		return new DruidDataSource(); 
	}

}

