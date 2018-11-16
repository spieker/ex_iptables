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
  use GenServer

  alias ExIptables.Rule
  alias ExIptables.Chain
  alias ExIptables.Adapters.FakeAdapter.Helpers

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

  def handle_call({:insert, chain, rulenum, args}, _from, state) do
    case Helpers.insert_rule(state, chain, rulenum, args) do
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

  def cmd(["--insert", chain, rulenum | args]),
    do: GenServer.call(__MODULE__, {:insert, chain, rulenum, args})

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

  def rule_to_list(%Rule{rule: rule}), do: rule
end
