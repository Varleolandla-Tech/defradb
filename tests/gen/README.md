# Automatic Documents Generation 

`AutoGenerate` and `AutoGenerateFromSDL` are a highly versatile function designed for dynamic document generation, perfect for testing and simulation purposes. 

`AutoGenerateFromSDL` creates documents based on a specified GQL SDL, which may contain multiple schema/collection definitions, allowing for extensive customization of data generation. 

The function generates documents adhering to a defined collection and it's configuration.
It interprets the types and relationships within the collection to create realistic, interconnected data structures.

`AutoGenerate` creates documents based on the provider collections' definitions (`[]client.CollectionDefinition`)

### Demand Calculation:

The functions calculate the 'demand' or the number of documents to generate based on the configuration provided.
For related types within the collection set, it intelligently adjusts the number of generated documents to maintain consistency in relationships (one-to-one, one-to-many, etc.).

In the absence of explicit demands, it deduces demands from the maximum required by related types or uses a default value if no relation-based demands are present.

The error will be returned if the demand for documents can not be satisfied. 
For example, a document expects at least 10 secondary documents, but the demand for secondary documents is 5.

## Configuration

Both functions `AutoGenerate` and `AutoGenerateFromSDL` can be configured using options.

Additionally, `AutoGenerateFromSDL` can be configured directly within the schema using annotations.
Options take precedence over in-schema configurations.

### In-schema Configuration:

Field values can be configured directly within the SDL doc using annotations after "#" (e.g., `# min: 1, max: 120` for an integer field).

At the moment, the following value configurations are supported:
- `min` and `max` for integer, float and relation fields. For relation fields, the values define the minimum and maximum number of related documents.
- `len` for string fields

Default value ranges are used when not explicitly set in the schema or via options.

### Customization with Options:

- `WithTypeDemand` and `WithTypeDemandRange` allow setting the specific number (or range) of documents for a given type.
- `WithFieldRange` and `WithFieldLen` override in-schema configurations for field ranges and lengths.
- `WithFieldGenerator` provides custom value generation logic for specific fields.
- `WithRandomSeed` ensures deterministic output, useful for repeatable tests.

## Examples

### Basic Document Generation:

```go
sdl := `
type User {
  name: String # len: 10
  age: Int # min: 18, max: 50
  verified: Boolean
  rating: Float # min: 0.0, max: 5.0
}`
docs, _ := AutoGenerateFromSDL(sdl, WithTypeDemand("User", 100))
```

### Custom Field Range:

Overrides the age range specified in the SDL doc.

```go
docs, _ := AutoGenerateFromSDL(sdl, WithTypeDemand("User", 50), WithFieldRange("User", "age", 25, 30))
```

### One-to-Many Relationship:

Generates User documents each related to multiple Device documents.

```go
sdl := `
type User { 
  name: String 
  devices: [Device] # min: 1, max: 3
}
type Device {
  model: String
  owner: User
}`
docs, _ := AutoGenerateFromSDL(sdl, WithTypeDemand("User", 10))
```

### Custom Value Generation:

Custom generation for age field.

```go
nameWithPrefix := func(i int, next func() any) any {
  return "user_" + next().(string)
}
docs, _ := AutoGenerateFromSDL(sdl, WithTypeDemand("User", 10), WithFieldGenerator("User", "name", nameWithPrefix))
```

## Conclusion

`AutoGenerateFromSDL` is a powerful tool for generating structured, relational data on the fly. Its flexibility in configuration and intelligent demand calculation makes it ideal for testing complex data models and scenarios.
