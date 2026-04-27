# Posts

This directory is for long-form OpenETR articles that should live in the repository and be renderable through GitHub Pages.

## Files

- [index.md](./index.md) is the Jekyll-rendered posts landing page.
- `docs/posts/<slug>.md` is the pattern for individual articles.
- [post-template.md](./post-template.md) is a starter file for new posts.

## Published posts

- [Introducing OpenETR](./introducing-openetr.md)

## Notes

- Content in `docs/posts` is part of the repository and can be linked from the landing page.
- It is not part of the Python package install payload because it is outside the `openetr/` package and is not listed in Poetry package includes.
