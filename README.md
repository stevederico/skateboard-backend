# Skateboard Backend Application

A backend API for the Skateboard application built with Deno and Express.

## Features

- User authentication (signup, signin)
- JWT token-based authorization
- Stripe integration for subscriptions
- MongoDB data storage

## Prerequisites

- Deno v2.2 or newer
- MongoDB running locally or a MongoDB Atlas account
- Stripe account for payment processing

## Environment Variables

Create a `.env` file in the root directory with the following variables:

```
PORT=8000
MONGO_URI=mongodb://localhost:27017
STRIPE_KEY=your_stripe_secret_key
STRIPE_ENDPOINT_SECRET=your_stripe_webhook_secret
JWT_SECRET=your_jwt_secret
```

## Stripe API key Recommendations
Create a restricted stripe api key with the following permissions
- checkout write
- products read
- price read
- customers read

## Stripe Webhook Events
- customer.subscription.created
- customer.subscription.deleted
- customer.subscription.updated

## Stripe Product
- You must add a lookup_key to the stripe product's price, this will be used by Stripe Checkout

## Installation and Running

1. Clone the repository
2. Set up your environment variables in `.env`
3. Run the application:

```bash
# Run in development mode (with file watching)
deno run --allow-net --allow-read --allow-env --allow-write --watch index.js
# or
npm run dev

# Run in production mode
deno run --allow-net --allow-read --allow-env --allow-write index.js
# or
npm start
```

## API Endpoints

- `POST /signup` - Create a new user
- `POST /signin` - Authenticate user
- `GET /me` - Get current user details
- `GET /isSubscriber` - Check subscription status
- `POST /create-checkout-session` - Create Stripe checkout session
- `POST /create-portal-session` - Create Stripe billing portal session
- `POST /webhook` - Handle Stripe webhooks

## License

MIT

## Contributing

We welcome contributions from the community! Please follow these guidelines:

1. Fork the repository.
2. Create a new branch for your feature or bug fix:
   ```sh
   git checkout -b feature/your-feature-name
   ```
3. Make your changes and commit them with descriptive messages.
4. Push your branch to your fork:
   ```sh
   git push origin feature/your-feature-name
   ```
5. Open a pull request against the `master` branch.

## Acknowledgements 

- [deno](https://github.com/denoland/deno)

## Contact

For any questions or support, please open an issue in this repository.
