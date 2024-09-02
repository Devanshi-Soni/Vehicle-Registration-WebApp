using AutoFixture;
using EntityFrameworkCoreMock;
using Microsoft.EntityFrameworkCore;
using Moq;
using VehicleRegistration.Core.Interfaces;
using VehicleRegistration.Core.Services;
using VehicleRegistration.Infrastructure;
using VehicleRegistration.Infrastructure.DataBaseModels;
using VehicleRegistration.WebAPI.Controllers;
using VehicleRegistration.WebAPI.Models;

namespace VehicleRegistrationAppTest
{
    public class VehicleServiceTest
    {
        private readonly Mock<ApplicationDbContext> _dbContext;
        private readonly Mock<IVehicleService> _vehicleService;
        private readonly IFixture _fixture;
        public VehicleServiceTest()
        {
            _fixture = new Fixture();
            
            //Creating Mock For Db context 
            DbContextMock<ApplicationDbContext> dbContextMock = new DbContextMock<ApplicationDbContext>( new DbContextOptionsBuilder<ApplicationDbContext>().Options);
            ApplicationDbContext dbContext = dbContextMock.Object;

            // inital data for DB by using mock 
            var vehiclesInitialData = new List<VehicleModel>() { };
            //mocks for DbSet 
            dbContextMock.CreateDbSetMock(temp => temp.VehiclesDetails, vehiclesInitialData); 
            //Create services based on mocked DbContext object
            _vehicleService = new Mock<IVehicleService>(dbContext);

            // fixture object for Creating vehicle data 
            var vehicle = _fixture.Build<VehicleModel>()
                                .Without(v => v.User) 
                                .With(v => v.VehicleId, Guid.NewGuid())
                                .With(v => v.VehicleNumber, "ABC123")
                                .With(v => v.VehicleOwnerName, "John Doe")
                                .With(v => v.OwnerContactNumber, "123-456-7890")
                                .With(v => v.VehicleClass, "Sedan")
                                .With(v => v.FuelType, "Gasoline")
                                .With(v => v.UserId, 1)
                                .Create();
            _vehicleService.Setup(v => v.GetVehicleByIdAsync(It.IsAny<Guid>())).ReturnsAsync(vehicle);
            
        }

        #region Add Vehicle

        // Test for Adding a Vehicle with Valid Data 
        [Fact]
        public async Task AddVehicle_WithProperData()
        {
            // Arrange
             var vehicle = _fixture.Build<VehicleModel>()
                      .Without(v => v.User) 
                      .Create();
            _vehicleService.Setup(v => v.AddVehicle(It.IsAny<VehicleModel>())).ReturnsAsync(vehicle);
            
            //Act
            var result = await _vehicleService.Object.AddVehicle(vehicle);
           
            //Assert
            Assert.NotNull(result);
            Assert.Equal(vehicle.VehicleId, result.VehicleId);
        }
        #endregion
        
        #region Edit Vehicle

         // Test for Editing a Vehicle with Valid Data
         [Fact]
         public async Task EditVehicle_WithProperData()
         {
            // Arrange
            var vehicle = _fixture.Build<VehicleModel>()
                               .Without(v => v.User) 
                               .Create();
            var userId = vehicle.UserId.ToString();

            _vehicleService.Setup(v => v.EditVehicle(It.IsAny<VehicleModel>(), userId)).ReturnsAsync(vehicle);
        
             // Act
             var result = await _vehicleService.Object.EditVehicle(vehicle, userId);
        
             // Assert
             Assert.NotNull(result);
             Assert.Equal(vehicle.VehicleId, result.VehicleId);
         }
        
         // Test for Editing a Vehicle that does not exist
         [Fact]
         public async Task EditVehicle_VehicleNotFound()
         {
            // Arrange
            var vehicle = _fixture.Build<VehicleModel>()
                                .Without(v => v.User) 
                                .Create();
            var userId = vehicle.UserId.ToString();

            _vehicleService.Setup(v => v.EditVehicle(It.IsAny<VehicleModel>(), userId))
                            .ThrowsAsync(new NullReferenceException("Vehicle not found."));
        
             // Assert
             await Assert.ThrowsAsync<NullReferenceException>(() => _vehicleService.Object.EditVehicle(vehicle, userId));
         }
        #endregion

        #region Delete Vehicle

        // Test for Deleting a Vehicle that does not exist
        [Fact]
        public async Task DeleteVehicle_VehicleNotFound()
        {
            // Arrange
            var vehicleId = Guid.NewGuid();
            _vehicleService.Setup(v => v.DeleteVehicle(vehicleId)).ReturnsAsync((VehicleModel)null);
        
            // Act
            var result = await _vehicleService.Object.DeleteVehicle(vehicleId);
        
            // Assert
            Assert.Null(result);
        }
        
        // Test for Deleting a Vehicle with Valid Data
        [Fact]
        public async Task DeleteVehicle_WithProperData()
        {
            // Arrange
            var vehicleId = Guid.NewGuid();
            _vehicleService.Setup(v => v.DeleteVehicle(vehicleId)).ReturnsAsync((VehicleModel)null);

            // Act
            var result = await _vehicleService.Object.DeleteVehicle(vehicleId);

            // Assert
            Assert.Null(result);
        }
        #endregion
        
        #region Get Vehicle By Id

        // Test for Getting Vehicle By Id with Valid Id
        [Fact]
        public async Task GetVehicleById_WithProperId()
        {
            // Arrange
            var vehicle = _fixture.Build<VehicleModel>()
                                 .Without(v => v.User) 
                                 .Create();
            var vehicleId = vehicle.VehicleId;

            _vehicleService.Setup(v => v.GetVehicleByIdAsync(vehicleId)).ReturnsAsync(vehicle);

            // Act
            var result = await _vehicleService.Object.GetVehicleByIdAsync(vehicleId);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(vehicle.VehicleId, result.VehicleId);
        }
        
        // Test for Getting Vehicle By Id with Invalid Id
        [Fact]
        public async Task GetVehicleById_WithInvalidId()
        {
            // Arrange
            var vehicleId = Guid.NewGuid();
        
            _vehicleService.Setup(v => v.GetVehicleByIdAsync(vehicleId)).ReturnsAsync((VehicleModel)null);
        
            // Act
            var result = await _vehicleService.Object.GetVehicleByIdAsync(vehicleId);
        
            // Assert
            Assert.Null(result);
        }
        
        #endregion
    }
}
