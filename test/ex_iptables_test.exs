defmodule ExIptablesTest do
  use ExUnit.Case
  alias ExIptables.Chain
  alias ExIptables.Rule

  doctest ExIptables

  setup do
    ExIptables.clear()
  end
end
