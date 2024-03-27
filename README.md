# Remitly 2024 summer internship assignment

This program validates AWS IAM policies against a set of rules, including a specific check for single asterisks (`*`) in the Resource field as per the assignment requirement.

## Key Features

*   Thorough validation of IAM policy structure:
    *   PolicyDocument existence and format
    *   PolicyName validity
    *   Version check
    *   Statement array checks
    *   Effect validation
    *   Action validation
    *   Resource validation (including 'aws' partition check and length check)

*   Specific check for single asterisk (`*`) in the Resource field.

*   Robust error handling with informative error messages.

## Installation 

**Prerequisites**

*   Node.js and npm (or yarn)

**Steps**

1.  Clone this repository:
    ```bash
    git clone https://github.com/KacperRebosz/remitly-internship-task
    ```

2.  Navigate to the project directory:
    ```bash
    cd remitly-internship-task
    ```

3.  Install dependencies:
    ```bash
    npm install 
    ``` 

## Usage

```bash
node app.js <filename.json>
```

**Example:**
```bash
node app.js examplePolicy.json
```

## Output

*   **Valid Policy:** The program will output `true`.
*   **Single Asterisk in Resource:**  The program will output `false`.
*   **Other Validation Errors:** The program will output a descriptive error message.

## Testing

This project includes test cases using Jest. To run the tests:

1.  Run the test cases:
    ```bash
    npx jest
    ```



