FROM mcr.microsoft.com/devcontainers/rust:1-1-bookworm

USER vscode

RUN sudo apt-get update

RUN rustup default nightly && \
	rustup component add clippy && \
	rustup component add rustfmt

RUN curl -L https://foundry.paradigm.xyz | bash

SHELL ["/bin/bash", "--login", "-i", "-c"]
RUN foundryup