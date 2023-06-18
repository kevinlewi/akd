# Introduction

**AKD** is a library for managing an auditable key directory, also known as a verifiable registry.

An auditable key directory provides an interface to a data structure that stores key-value mappings in a database in a verifiable manner. The data structure is similar to that of a Python dict, where directory entries are indexed by keys, and allow for storing a value with some key and then extracting the value given the key.

Keys can also be updated to be associated with different values. Each batch of updates to these key-value mappings are associated with an epoch along with a commitment to the database of entries at that point in time. The server that controls the database can use this library to generate proofs of inclusion to clients that wish to query entries in the database. These proofs can be verified by a client against the corresponding commitment to the database. We can think of this data structure intuitively as a verifiable dictionary.

It is ideal for creating product or API documentation, tutorials, course materials or anything that requires a clean,
easily navigable and customizable presentation.

* Lightweight [Markdown] syntax helps you focus more on your content
* Integrated [search] support
* Color [syntax highlighting] for code blocks for many different languages
* [Theme] files allow customizing the formatting of the output
* [Preprocessors] can provide extensions for custom syntax and modifying content
* [Backends] can render the output to multiple formats
* Written in [Rust] for speed, safety, and simplicity
* Automated testing of [Rust code samples]

This guide is an example of what mdBook produces.
mdBook is used by the Rust programming language project, and [The Rust Programming Language][trpl] book is another fine example of mdBook in action.

[Markdown]: format/markdown.md
[search]: guide/reading.md#search
[syntax highlighting]: format/theme/syntax-highlighting.md
[theme]: format/theme/index.html
[preprocessors]: format/configuration/preprocessors.md
[backends]: format/configuration/renderers.md
[Rust]: https://www.rust-lang.org/
[trpl]: https://doc.rust-lang.org/book/
[Rust code samples]: cli/test.md

## Contributing

mdBook is free and open source. You can find the source code on
[GitHub](https://github.com/rust-lang/mdBook) and issues and feature requests can be posted on
the [GitHub issue tracker](https://github.com/rust-lang/mdBook/issues). mdBook relies on the community to fix bugs and
add features: if you'd like to contribute, please read
the [CONTRIBUTING](https://github.com/rust-lang/mdBook/blob/master/CONTRIBUTING.md) guide and consider opening
a [pull request](https://github.com/rust-lang/mdBook/pulls).

## License

The mdBook source and documentation are released under
the [Mozilla Public License v2.0](https://www.mozilla.org/MPL/2.0/).