defmodule MiscTest.GRPC do
  use ExUnit.Case, async: true

  alias Misc.Protos.{HelloRequest, HelloReply, Greeter.Stub}

  doctest Misc.GRPC

  setup_all do
    Misc.GRPC.Supervisor.start_link(50053)
    {:ok, channel} = GRPC.Stub.connect("localhost:50053")
    [channel: channel]
  end

  test "basic hello world", %{channel: channel} do
    request = HelloRequest.new(name: "bob")
    assert {:ok, response} = Stub.say_hello(channel, request)
    assert response.message == "Hello bob"
  end

  test "basic streaming back works", %{channel: channel} do
    request = HelloRequest.new(name: "bob")
    assert {:ok, stream} = Stub.say_hello_stream_reply(channel, request)
    assert [{:ok, response}] = stream |> Enum.to_list()
    assert response.message == "Hello bob"
  end

  test "bi streaming works", %{channel: channel} do
    request = HelloRequest.new(name: "bob")
    stream = Stub.say_hello_bidi_stream(channel)
    GRPC.Stub.send_request(stream, request)
    GRPC.Stub.send_request(stream, request, end_stream: true)
    assert {:ok, finished_stream} = GRPC.Stub.recv(stream)
    finished_list = Enum.to_list(finished_stream)
    assert length(finished_list) == 2

    for {:ok, response} <- finished_list do
      assert response.message == "Hello bob"
    end
  end
end
