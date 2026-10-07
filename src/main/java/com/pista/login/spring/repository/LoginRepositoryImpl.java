package com.pista.login.spring.repository;
import org.springframework.stereotype.Repository;
import com.pista.login.domain.repository.LoginRepository; 
import com.pista.login.domain.entity.User;
import com.pista.login.spring.repository.adapter.LoginRepositoryAdapter;
import com.pista.login.spring.repository.mongo.LoginRepositoryWithMongoDB;
import com.pista.login.spring.repository.orm.LoginOrmMongo;

@Repository
public class LoginRepositoryImpl implements LoginRepository {

    private final LoginRepositoryWithMongoDB repository;

    public LoginRepositoryImpl(LoginRepositoryWithMongoDB repository) {
        this.repository = repository;
    }

    @Override
    public User salvar(User login) {
        LoginOrmMongo orm = LoginRepositoryAdapter.castEntity(login);
        return LoginRepositoryAdapter.castOrm(repository.save(orm));
    }

    @Override
    public void deletar(String id) {
        repository.deleteById(id);
    }

    @Override
    public User findByUsername(String username) {
        LoginOrmMongo orm = repository.findByUsername(username);

        if (orm == null) {
            return null;
        }

        return LoginRepositoryAdapter.castOrm(orm);
    }

    @Override
    public User findByEmail(String email) {
        LoginOrmMongo orm = repository.findByEmail(email);

        if (orm == null) {
            return null;
        }

        return LoginRepositoryAdapter.castOrm(orm);
    }
}