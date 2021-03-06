defmodule OMG.Eth.MixProject do
  use Mix.Project

  require Logger

  def project do
    [
      app: :omg_eth,
      version: OMG.Umbrella.MixProject.umbrella_version(),
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.6",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls]
    ]
  end

  def application do
    [
      env: [
        child_block_interval: 1000
      ],
      extra_applications: [:logger]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:prod), do: ["lib"]
  defp elixirc_paths(_), do: ["lib", "test/support"]

  defp deps do
    [
      {:abi, git: "https://github.com/omisego/abi.git", branch: "encode_dynamic_types"},
      {:ethereumex, git: "https://github.com/omisego/ethereumex.git", branch: "request_timeout2", override: true},
      {:exexec, git: "https://github.com/pthomalla/exexec.git", branch: "add_streams", runtime: true},
      # TODO: we only need in :dev and :test here, but we need in :prod too in performance
      #       then there's some unexpected behavior of mix that won't allow to mix these, see
      #       [here](https://elixirforum.com/t/mix-dependency-is-not-locked-error-when-building-with-edeliver/7069/3)
      {:briefly, "~> 0.3"},
      {
        :plasma_contracts,
        git: "https://github.com/omisego/plasma-contracts",
        branch: "v0.0",
        sparse: "contracts/",
        compile: contracts_compile(),
        app: false,
        only: [:dev, :test]
      }
    ]
  end

  defp contracts_compile do
    mixfile_path = __DIR__
    contracts_dir = Path.join(mixfile_path, "../../deps/plasma_contracts/contracts")

    contract_paths =
      ["RootChain.sol", "MintableToken.sol"]
      |> Enum.map(&Path.join(contracts_dir, &1))
      |> Enum.join(" ")

    output_path = Path.join(mixfile_path, "../../_build/contracts")
    "solc #{contract_paths} --overwrite --abi --bin --optimize --optimize-runs 1 -o #{output_path}"
  end
end
