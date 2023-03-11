# arkworks Circuit Examples

There are examples of circuits useing the [arkworks](https://arkworks.rs/) libraries.

1. Multiplication

$$
c_{public} = a_{private} * b_{private}
$$

2. Cubic polynomial

$$
c_{public} = x^3_{private} + x_{private} + 5
$$

## Running the Tests

To run the tests, simply execute the following command:

```sh
cargo test --release
```
