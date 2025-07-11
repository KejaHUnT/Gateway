# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app
COPY . ./
RUN dotnet publish KejaHunT_Gateway.csproj -c Release -o /out

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /out .
ENTRYPOINT ["dotnet", "KejaHunT_Gateway.dll"]