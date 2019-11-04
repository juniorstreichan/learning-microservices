package dev.juniorstreichan.core.model;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.NotNull;

@Entity
@Data
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
public class AppUser implements AbstractEntity {
    @Id
    @GeneratedValue(generator = "app_user_generator")
    @SequenceGenerator(
            name = "app_user_generator",
            sequenceName = "app_user_sequence",
            initialValue = 1000
    )
    private Long id;

    @NotNull(message = "The field 'username' is mandatory")
    @Column(nullable = false)
    private String username;

    @NotNull(message = "The field 'password' is mandatory")
    @Column(nullable = false)
    private String password;

}
