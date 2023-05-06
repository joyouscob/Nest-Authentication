import { BlacklistMiddleware } from './blacklist.middleware';

describe('BlacklistMiddleware', () => {
  it('should be defined', () => {
    expect(new BlacklistMiddleware()).toBeDefined();
  });
});
