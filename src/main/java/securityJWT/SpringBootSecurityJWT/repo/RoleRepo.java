package securityJWT.SpringBootSecurityJWT.repo;

import org.springframework.data.jpa.repository.JpaRepository;
import securityJWT.SpringBootSecurityJWT.domain.Role;

public interface RoleRepo extends JpaRepository<Role,Long>
{
    Role findByName(String name);
}
