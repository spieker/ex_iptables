defmodule ExIptables.Adapters.FakeAdapter do
  @moduledoc """
  The `ExIptables.FakeAdapter` can be used for application testing. It
  implements a GenServer for keeping track of the current state. To use the
  fake adapter, set the `:adapter` value of `:ex_iptables` accordingly.

  ## Example

      config :ex_iptables, :adapter, ExIptables.Adapters.FakeAdapter

  When using the FakeAdapter, it must be started before using any ExIptables
  command.

  ##  Example

      iex> ExIptables.Adapters.FakeAdapter.start()
      :ok

  For clearing the state before/after each test run, `reset/0` can be used on
  the adapter.

  ## Example

      iex> ExIptables.start()
      ...> ExIptables.Adapters.FakeAdapter.reset()

  """
  defmodule Helpers do
    alias ExIptables.Chain
    alias ExIptables.Rule

    def chain(state, name) do
      case Map.get(state, name) do
        nil -> {:error, 1}
        result -> {:ok, result}
      end
    end

    def rule?(state, chain, %Rule{} = rule) do
      case chain(state, chain) do
        {:ok, %Chain{rules: rules}} ->
          case Enum.member?(rules, rule) do
            true -> {:ok, ""}
            false -> {:error, 1}
          end

        {:error, _} = error ->
          error
      end
    end

    def rule?(state, chain_name, args), do: rule?(state, chain_name, args_to_rule(args))

    def append_rule(state, chain_name, %Rule{} = rule) do
      case chain(state, chain_name) do
        {:ok, %Chain{rules: rules} = chain} ->
          chain = %Chain{chain | rules: rules ++ [rule]}
          new_state = Map.put(state, chain.name, chain)
          {:ok, new_state}

        {:error, _} = error ->
          error
      end
    end

    def append_rule(state, chain_name, args),
      do: append_rule(state, chain_name, args_to_rule(args))

    def delete_rule(state, chain_name, %Rule{} = rule) do
      case rule?(state, chain_name, rule) do
        {:ok, ""} ->
          {:ok, %Chain{rules: rules} = chain} = chain(state, chain_name)
          chain = %Chain{chain | rules: List.delete(rules, rule)}
          new_state = Map.put(state, chain_name, chain)
          {:ok, new_state}

        {:error, _} = error ->
          error
      end
    end

    def delete_rule(state, chain_name, args),
      do: delete_rule(state, chain_name, args_to_rule(args))

    def set_policy(state, chain_name, target) do
      case chain(state, chain_name) do
        {:ok, %Chain{} = chain} ->
          chain = %Chain{chain | target: target}
          new_state = Map.put(state, chain_name, chain)
          {:ok, new_state}

        {:error, _} = error ->
          error
      end
    end

    def args_to_rule(args) do
      [_ | moved_args] = args

      [Enum.take_every(args, 2), Enum.take_every(moved_args, 2)]
      |> Enum.zip()
      |> Enum.reduce(%Rule{}, fn
        {key, val}, rule ->
          key =
            key
            |> String.slice(2..-1)
            |> String.replace("-", "__")
            |> String.to_atom()

          Map.put(rule, key, val)
      end)
    end
  end

  use GenServer

  alias ExIptables.Rule
  alias ExIptables.Chain

  @empty_table %{
    "INPUT" => %ExIptables.Chain{name: "INPUT"},
    "FORWARD" => %ExIptables.Chain{name: "FORWARD"},
    "OUTPUT" => %ExIptables.Chain{name: "OUTPUT"}
  }

  def start do
    __MODULE__
    |> Process.whereis()
    |> start_or_return()
  end

  defp start_or_return(nil), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  defp start_or_return(pid) do
    case Process.alive?(pid) do
      true ->
        {:ok, pid}

      false ->
        start_or_return(nil)
    end
  end

  def init(_) do
    {:ok, @empty_table}
  end

  def handle_call(:clear, _from, _state) do
    {:reply, :ok, @empty_table}
  end

  def handle_call({:list}, _from, state) do
    chains =
      state
      |> Map.values()
      |> Enum.map(&chain_to_string(&1))
      |> Enum.join("\n")

    {:reply, {:ok, "#{chains}\n"}, state}
  end

  def handle_call({:list, name}, _from, state) do
    chains =
      state
      |> Map.get(name)
      |> chain_to_string()

    case chains do
      {:error, _} = error -> {:reply, error, state}
      _ -> {:reply, {:ok, chains}, state}
    end
  end

  def handle_call({:check, chain, args}, _from, state) do
    {:reply, Helpers.rule?(state, chain, args), state}
  end

  def handle_call({:append, chain, args}, _from, state) do
    case Helpers.append_rule(state, chain, args) do
      {:ok, new_state} ->
        {:reply, {:ok, ""}, new_state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  def handle_call({:delete, chain, args}, _from, state) do
    case Helpers.delete_rule(state, chain, args) do
      {:ok, new_state} ->
        {:reply, {:ok, ""}, new_state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  def handle_call({:set_policy, chain, target}, _from, state) do
    case Helpers.set_policy(state, chain, target) do
      {:ok, new_state} ->
        {:reply, {:ok, ""}, new_state}

      {:error, _} = error ->
        {:reply, error, state}
    end
  end

  def clear(), do: GenServer.call(__MODULE__, :clear)

  def cmd(["--append", chain | args]), do: GenServer.call(__MODULE__, {:append, chain, args})
  def cmd(["--check", chain | args]), do: GenServer.call(__MODULE__, {:check, chain, args})
  def cmd(["--delete", chain | args]), do: GenServer.call(__MODULE__, {:delete, chain, args})
  def cmd(["--insert", _chain, _rulenum | _args]), do: raise("Not yet implemented")
  def cmd(["--replace", _chain, _rulenum | _args]), do: raise("Not yet implemented")
  def cmd(["--list-rules"]), do: GenServer.call(__MODULE__, {:list})
  def cmd(["--list-rules", chain]), do: GenServer.call(__MODULE__, {:list, chain})
  def cmd(["--flush"]), do: raise("Not yet implemented")
  def cmd(["--flush", _chain]), do: raise("Not yet implemented")
  def cmd(["--zero"]), do: raise("Not yet implemented")
  def cmd(["--zero", _chain]), do: raise("Not yet implemented")
  def cmd(["--zero", _chain, _rulenum]), do: raise("Not yet implemented")
  def cmd(["--new-chain", _chain]), do: raise("Not yet implemented")
  def cmd(["--delete-chain"]), do: raise("Not yet implemented")
  def cmd(["--delete-chain", _chain]), do: raise("Not yet implemented")

  def cmd(["--policy", chain, target]),
    do: GenServer.call(__MODULE__, {:set_policy, chain, target})

  def cmd(["--rename-chain", _old_name, _new_name]), do: raise("Not yet implemented")

  defp chain_to_string(nil), do: {:error, 1}

  defp chain_to_string(%Chain{name: name, target: target, rules: rules}) do
    (["-P #{name} #{target}"] ++ Enum.map(rules, &"-A #{name} #{rule_to_list(&1)}"))
    |> Enum.join("\n")
  end

  def rule_to_list(%Rule{} = rule) do
    rule
    |> Map.from_struct()
    |> Enum.reduce([], fn
      {_, nil}, res -> res
      {:protocol, value}, res -> res ++ ["-p", value]
      {:source, value}, res -> res ++ ["-s", value]
      {:destination, value}, res -> res ++ ["-d", value]
      {:match, value}, res -> res ++ ["-m", value]
      {:jump, value}, res -> res ++ ["-j", value]
      {:goto, value}, res -> res ++ ["-g", value]
      {:in_interface, value}, res -> res ++ ["-i", value]
      {:out_interface, value}, res -> res ++ ["-o", value]
      {:fragment, value}, res -> res ++ ["-f", value]
      {:set_counters, value}, res -> res ++ ["-c", value]
    end)
    |> Enum.join(" ")
  end
end
