import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
@Entity()
export class User {
  @PrimaryGeneratedColumn({ type: 'bigint' })
  id: number;

  @Column()
  first_name: string;

  @Column()
  last_name: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ default: false })
  isActive: boolean;

  @Column({ nullable: true })
  reset_token: string;

  @Column({ default: 0 })
  reset_count: number;

  @Column({ nullable: true })
  activation_token: string;

  @CreateDateColumn()
  created_at;

  @UpdateDateColumn()
  updated_at;

  @Column({ default: false })
  is_admin: boolean;
}
