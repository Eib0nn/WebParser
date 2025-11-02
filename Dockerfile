FROM gcc:12 AS cpp-builder

WORKDIR /build

RUN apt-get update && \
    apt-get install -y nlohmann-json3-dev && \
    rm -rf /var/lib/apt/lists/*

COPY engine/types.h engine/parsefn.cpp engine/engine.cpp ./

RUN g++ -shared -fPIC -o libengine.so \
    parsefn.cpp engine.cpp \
    -I. \
    -std=c++17 \
    -O2 \
    -Wall

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src
COPY glue/parser.csproj ./
RUN dotnet restore

COPY glue/*.cs ./
RUN dotnet publish -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:8.0

WORKDIR /app

COPY --from=build /app/publish .

COPY --from=cpp-builder /build/libengine.so ./

ENV LD_LIBRARY_PATH=/app:$LD_LIBRARY_PATH

ENV ASPNETCORE_URLS=http://+:${PORT:-8080}

EXPOSE 8080

ENTRYPOINT ["dotnet", "parser.dll"]