package com.pista.login.spring.repository.mongo;
import org.springframework.data.mongodb.repository.MongoRepository;
import com.pista.login.spring.repository.orm.LoginOrmMongo;

public interface LoginRepositoryWithMongoDB extends MongoRepository<LoginOrmMongo, String> {
    LoginOrmMongo findByUsername(String username);
    LoginOrmMongo findByEmail(String email);
}