package securityJWT.SpringBootSecurityJWT.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import securityJWT.SpringBootSecurityJWT.domain.User;

public interface UserRepo extends JpaRepository<User,Long>
{
    User findByUsername(String username);
}
