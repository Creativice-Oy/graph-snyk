import { createIntegrationEntity } from '@jupiterone/integration-sdk-core';
import { Entities } from '../../constants';
import { User } from '../../types';

export function createUserEntity(user: User) {
  return createIntegrationEntity({
    entityData: {
      source: user,
      assign: {
        _class: Entities.USER._class,
        _type: Entities.USER._type,
        _key: user.id as string,
        name: user.name,
        displayName: user.name,
        username: user.username,
        email: user.email,
        role: user.role,
        admin: user.role === 'admin',
        active: true,
      },
    },
  });
}
