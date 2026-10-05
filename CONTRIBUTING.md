# Contributing to Pixplace

Thanks for your interest! Pixplace is an experimental hobby project and help is very welcome.

## Ways to help

- Fix bugs and polish the UI
- Improve the experimental views for **mobile and foldable devices** (`client/viewtest.*`, `client/viewapple.*`)
- Add or improve translations in `lang/`
- Improve documentation, add tests
- Review security-relevant code

## Ground rules

- **English first.** Code, comments, commit messages and issues in English. User-facing text goes through the language files (`lang/*.lang`) – add the key to `en.lang` first.
- **No new runtime dependencies** for the server. It is intentionally Python standard library only.
- **Never trust the client.** Every permission and limit must be enforced in `server/server.py`.
- Keep pull requests focused and describe what and why.
- Do not add code, assets or specifications taken from other chat programs.

## Workflow

1. Fork and create a branch
2. Make your change
3. Run `make check` (Python syntax, JavaScript syntax, language-file completeness)
4. Open a pull request

## Reporting bugs

Open an issue with steps to reproduce, your browser/OS and the server version (`PP_VERSION`). For security issues, open an issue too and see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT License.
