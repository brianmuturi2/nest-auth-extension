import { User } from "src/users/entities/user.entity";
import { Column, Entity, ManyToOne, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class ApiKey {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    key: string;

    @Column()
    uuid: string;

    @ManyToOne((type) => User, (user) => user.apiKeys)
    user: User;

    // NOTE: As an exercise, you could create a new entity called "Scope" and establish
    // a Many to Many relashionship between API Keys and Scopes. With the scopes feature, users
    // could selectively grant specific permissions/scopes to given API Keys. For example, some
    // API Keys could only let 3rd party applications "Read" data, but not modify it, e.t.c
    // @Column()
    // scopes: Scope[];
}
