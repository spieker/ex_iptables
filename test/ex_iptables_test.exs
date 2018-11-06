defmodule ExIptablesTest do
  use ExUnit.Case
  doctest ExIptables

  setup do
    ExIptables.clear()
  end
end
