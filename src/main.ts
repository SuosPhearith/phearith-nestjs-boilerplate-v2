import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as express from 'express';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.use('/uploads', express.static('uploads'));
  app.use(cookieParser());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  // Enable CORS and Credential
  app.enableCors({
    origin: [
      process.env.ORIGIN_URL_1,
      process.env.ORIGIN_URL_2,
      process.env.ORIGIN_URL_3,
    ],
    credentials: true,
  });
  await app.listen(process.env.PORT || 3000);
  console.log('===============================');
  console.log('||   🚀  Running Server  🚀  ||');
  console.log('===============================');
  console.log(`||     🌐  Port: ${process.env.PORT || 3000} 🌐     ||`);
  console.log('===============================');
}
bootstrap();
