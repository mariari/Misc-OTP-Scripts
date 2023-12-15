defmodule Misc.MixProject do
  use Mix.Project

  def project do
    [
      app: :misc,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:gen_stage, []},
      {:typed_struct, "~> 0.3.0"},
      {:beam_file, "~> 0.5.1"},
      {:grpc, "~> 0.7.0"},
      {:protobuf, "~> 0.10.0"},
      {:dialyxir, "~> 1.3", only: [:dev], runtime: false}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
