import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieparser from 'cookie-parser'

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.use(cookieparser())
  app.enableCors({
    origin: 'http://localhost:3000',
    credentials: true,
  })
  await app.listen(5000);
}
bootstrap();
