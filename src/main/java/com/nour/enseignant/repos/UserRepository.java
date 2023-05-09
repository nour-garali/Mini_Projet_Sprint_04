package com.nour.enseignant.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import com.nour.enseignant.entities.User;
public interface UserRepository extends JpaRepository<User, Long> {
User findByUsername (String username);
}