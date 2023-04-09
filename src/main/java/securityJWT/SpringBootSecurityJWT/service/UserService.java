package securityJWT.SpringBootSecurityJWT.service;

import securityJWT.SpringBootSecurityJWT.domain.Role;
import securityJWT.SpringBootSecurityJWT.domain.User;

import java.util.List;

public interface UserService
{
    User saveUser(User user);
    Role saveRole(Role role);

    void addRoleToUser(String username,String roleName);
    User getUser(String username);
    List<User> getUsers();
}
